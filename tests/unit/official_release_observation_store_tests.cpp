//------------------------------------------------------------------------------
/**
 * @file official_release_observation_store_tests.cpp
 * @brief 公式release観測と自動探索cacheの端末内永続化単体試験実装。
 * @version 01.01.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Binding key試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  URL非保持cacheの往復、改ざんと分離破棄試験を追加。
 * </pre>
 *
 * @note ProductionのProgramData、実device、networkを使わず、架空観測、cacheとkeyを一時directoryへ
 *       保存して破損・重複・上限の拒否を検証します。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "official_release_observation_store_tests.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_release_observation_store.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view STATE_FILE_NAME			 = L"release-observations.bin" ;	// 固定state名。
constexpr std::wstring_view BINDING_SECRET_FILE_NAME = L"binding-secret.bin" ;			// 固定key名。
constexpr std::wstring_view DISCOVERY_CACHE_FILE_NAME =
	L"official-discovery-cache.bin" ;	// 固定cache snapshot名。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 試験専用directoryを作成する。
 *
 * OSが生成した一意一時file名を同じ場所のdirectoryへ変換する。
 *
 * @param[out] root 成功時に試験が所有する絶対directory path。
 * @return Directoryを作成できた場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createTestDirectory( std::wstring &root)
{
	root.clear() ;
	std::array<wchar_t, MAX_PATH + 1U> temporaryPath{} ;	// Temp root取得buffer。
	const DWORD pathLength = GetTempPathW( static_cast<DWORD>( temporaryPath.size()),
										  // Temp root文字数。
										  temporaryPath.data()) ;
	// 一時directoryのpathが空またはbufferを超える場合は試験領域を作らない。
	if( pathLength == 0U || pathLength >= temporaryPath.size()) {
		return false ;
	}

	std::array<wchar_t, MAX_PATH + 1U> temporaryFile{} ;	// 一意file名取得buffer。
	// 一意な一時名を取得できなければ試験directoryを作らない。
	if( GetTempFileNameW( temporaryPath.data(), L"dco", 0U, temporaryFile.data()) == 0U) {
		return false ;
	}

	static_cast<void>( DeleteFileW( temporaryFile.data())) ;
	// 試験directory作成に失敗した場合は未確保のpathを返さない。
	if( CreateDirectoryW( temporaryFile.data(), nullptr) == FALSE) {
		return false ;
	}

	root.assign( temporaryFile.data()) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 試験専用directoryを削除する。
 *
 * 固定stateと同directoryの一時fileだけをbest-effortで削除する。
 *
 * @param[in] root createTestDirectoryが返した専用path。
 */
//------------------------------------------------------------------------------
void removeTestDirectory( const std::wstring_view root) noexcept
{
	try {
		const std::filesystem::path ownedRoot( root) ;	// 試験が所有する削除root。
		// 試験root直下のstore生成fileだけを削除する。
		for( const std::filesystem::directory_entry &entry :
			std::filesystem::directory_iterator( ownedRoot)) {
			std::error_code error ;	// 個別file削除のbest-effort結果。
			static_cast<void>( std::filesystem::remove( entry.path(), error)) ;
		}

		std::error_code error ;	// Root削除のbest-effort結果。
		static_cast<void>( std::filesystem::remove( ownedRoot, error)) ;
	} catch( ...) {
		// Test cleanup失敗をprocess外へ伝播せず、後続assertionを実行可能にする。
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 架空の正常release観測を作成する。
 *
 * Device fingerprintと公開product keyだけをtestごとに変える。
 *
 * @param[in] fingerprintCharacter 小文字hexの繰返し文字。
 * @return 実device情報を含まない保存可能な架空観測。
 */
//------------------------------------------------------------------------------
[[nodiscard]] LocalOfficialReleaseObservation makeObservation( const wchar_t fingerprintCharacter)
{
	LocalOfficialReleaseObservation observation ;	// Storeへ渡す架空観測。
	observation.binding.deviceBindingFingerprint = std::wstring( 64U, fingerprintCharacter) ;
	observation.binding.providerId				 = L"fictional-provider" ;
	observation.binding.sourceId				 = L"fictional-source" ;
	observation.binding.familyId				 = L"fictional-family" ;
	observation.binding.productKey				 = L"product-" ;
	observation.binding.productKey.push_back( fingerprintCharacter) ;
	observation.binding.branch							   = L"windows-x64" ;
	observation.environment.operatingSystemFingerprint	   = std::wstring( 64U, L'b') ;
	observation.environment.deviceConfigurationFingerprint = std::wstring( 64U, L'c') ;
	observation.environment.policyRevision				   = 7U ;
	observation.environment.parserRevision				   = 3U ;
	observation.releaseKey								   = L"release-2026-09" ;
	observation.packageVersion							   = L"10.20.30.40" ;
	observation.publishedSha256							   = std::wstring( 64U, L'd') ;
	observation.observedFileTime						   = 1U ;
	return observation ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空のURL非保持公式自動探索cache entryを作成します。
 *
 * PositiveはIntel固定rootと一payload、negativeはASIX固定rootへ結合します。
 *
 * @param[in] kind Positiveまたは正常な二つのnegative結果です。
 * @return 永続化validatorに合格する架空entryです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialDiscoveryCacheEntry makeDiscoveryCacheEntry(
	const OfficialDiscoveryCacheEntryKind kind)
{
	OfficialDiscoveryCacheEntry entry ;	// Storeへ渡すURL非保持の架空entry。
	entry.kind = kind ;
	// Positiveとnegativeを別の組み込み固定rootへ結合します。
	if( kind == OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD) {
		entry.providerId = INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
		entry.policyId	 = INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID ;
		entry.recordFingerprint.bytes.fill( static_cast<std::byte>( 0x11U)) ;
		entry.payloads.push_back( OfficialDiscoveryCachedPayload{
			.payloadOrdinal			  = 0U,
			.payloadResourceId		  = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
			.payloadKind			  = OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
			.fileDisplayName		  = L"fictional-driver.zip",
			.productFamily			  = L"Fictional Ethernet Family",
			.operatingSystem		  = L"Windows 11 x64",
			.packageVersion			  = L"3.0.0",
			.publishedDate			  = L"2026-09-15",
			.publishedSizeBytes		  = 4'096U,
			.publishedSha256Available = true,
			.declaredPublisher		  = L"Fictional Device Vendor",
			.terms					  = OfficialDistributionTerms::ACCEPTANCE_REQUIRED,
			.eulaRevision			  = L"fixture-eula-v1"}) ;
	} else {
		entry.providerId = ASIX_AX88179A_PROVIDER_ID ;
		entry.policyId	 = ASIX_OFFICIAL_SOURCE_POLICY_ID ;
	}

	entry.rootResourceId	 = OFFICIAL_LANDING_RESOURCE_ID ;
	entry.policyRevision	 = OFFICIAL_DISCOVERY_POLICY_REVISION ;
	entry.parserId			 = L"fictional-cache-parser-v1" ;
	entry.parserRevision	 = 1U ;
	entry.observedUtcSeconds = 30'000U ;
	entry.expiresUtcSeconds =
		entry.observedUtcSeconds + (kind == OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD
										? OFFICIAL_DISCOVERY_POSITIVE_FRESH_SECONDS
										: OFFICIAL_DISCOVERY_NEGATIVE_FRESH_SECONDS) ;
	entry.operatingSystemFingerprint	 = std::wstring( 64U, L'a') ;
	entry.deviceConfigurationFingerprint = std::wstring( 64U, L'b') ;
	return entry ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの架空cache entryが全永続fieldで一致するか確認します。
 *
 * @param[in] left 比較する一方のentryです。
 * @param[in] right 比較する他方のentryです。
 * @return 永続化対象fieldが全て一致する場合trueです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool discoveryCacheEntriesEqual( const OfficialDiscoveryCacheEntry &left,
											  const OfficialDiscoveryCacheEntry &right) noexcept
{
	return left.schemaRevision == right.schemaRevision && left.kind == right.kind &&
		   left.providerId == right.providerId && left.policyId == right.policyId &&
		   left.rootResourceId == right.rootResourceId &&
		   left.policyRevision == right.policyRevision && left.parserId == right.parserId &&
		   left.parserRevision == right.parserRevision &&
		   left.recordFingerprint.bytes == right.recordFingerprint.bytes &&
		   left.payloads == right.payloads && left.observedUtcSeconds == right.observedUtcSeconds &&
		   left.expiresUtcSeconds == right.expiresUtcSeconds &&
		   left.operatingSystemFingerprint == right.operatingSystemFingerprint &&
		   left.deviceConfigurationFingerprint == right.deviceConfigurationFingerprint ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの架空観測が全fieldで一致するか確認する。
 *
 * Round-tripでfield欠落や順序変更がないことを確認する。
 *
 * @param[in] left 比較する一方の観測。
 * @param[in] right 比較する他方の観測。
 * @return 永続化対象fieldが全て一致する場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool observationsEqual( const LocalOfficialReleaseObservation &left,
									 const LocalOfficialReleaseObservation &right) noexcept
{
	return left.binding.deviceBindingFingerprint == right.binding.deviceBindingFingerprint &&
		   left.binding.providerId == right.binding.providerId &&
		   left.binding.sourceId == right.binding.sourceId &&
		   left.binding.familyId == right.binding.familyId &&
		   left.binding.productKey == right.binding.productKey &&
		   left.binding.branch == right.binding.branch &&
		   left.environment.operatingSystemFingerprint ==
			   right.environment.operatingSystemFingerprint &&
		   left.environment.deviceConfigurationFingerprint ==
			   right.environment.deviceConfigurationFingerprint &&
		   left.environment.policyRevision == right.environment.policyRevision &&
		   left.environment.parserRevision == right.environment.parserRevision &&
		   left.releaseKey == right.releaseKey && left.packageVersion == right.packageVersion &&
		   left.publishedSha256 == right.publishedSha256 &&
		   left.observedFileTime == right.observedFileTime &&
		   left.pendingReason == right.pendingReason ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定した保存fileの末尾byteを変更します。
 *
 * Headerを保ったままpayload SHA-256不一致を作成する。
 *
 * @param[in] root 試験専用store root。
 * @param[in] fileName Storeが使用する固定basenameです。
 * @return 一byteを変更してflushできた場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool corruptStoredFile( const std::wstring_view root, const std::wstring_view fileName)
{
	const std::filesystem::path path =
		// 改ざんする固定state path。
		std::filesystem::path( root) / fileName ;
	std::fstream file( path, std::ios::binary | std::ios::in | std::ios::out) ;	// 所有stream。
	// 保存fileを開けなければ末尾の変形試験を開始しない。
	if( !file) {
		return false ;
	}

	file.seekg( -1, std::ios::end) ;
	char value{} ;	// 末尾から読み取るpayload byte。
	file.read( &value, 1) ;
	// 末尾byteを読み取れなければ未取得値による差替えを行わない。
	if( !file) {
		return false ;
	}

	value = static_cast<char>( static_cast<unsigned char>( value) ^ 0x01U) ;
	file.seekp( -1, std::ios::end) ;
	file.write( &value, 1) ;
	file.flush() ;
	return file.good() ;
}

//------------------------------------------------------------------------------
/**
 * @brief Binding secretを全0の不正fileへ置き換える。
 *
 * 実credentialを使わず、次の読取りで再生成すべきkeyを作る。
 *
 * @param[in] root 試験専用store root。
 * @return 固定32 byteの不正fileを保存できた場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool corruptBindingSecret( const std::wstring_view root)
{
	const std::filesystem::path path =
		// 置換対象の固定key path。
		std::filesystem::path( root) / BINDING_SECRET_FILE_NAME ;
	std::ofstream file( path, std::ios::binary | std::ios::trunc) ;	// 所有出力stream。
	// binding secretを開けない場合は不正fileの生成を失敗とする。
	if( !file) {
		return false ;
	}

	const std::array<char, 32U> zero{} ;	// Storeが拒否する全0 key。
	file.write( zero.data(), static_cast<std::streamsize>( zero.size())) ;
	file.flush() ;
	return file.good() ;
}

//------------------------------------------------------------------------------
/**
 * @brief Missing、round-trip、空snapshotを検証する。
 *
 * 二recordの順序と全field、明示的な空snapshotを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testRoundTrip( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore store( root) ;	// Production ACLを使わない試験store。
	ReleaseObservationStoreResult	result ;		// Load結果。
	DRIVERCRATE_EXPECT( context, store.load( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == ReleaseObservationStoreState::MISSING) ;

	const std::array observations{makeObservation( L'a'),
								  // 保存順を確認する二観測。
								  makeObservation( L'e')} ;
	DRIVERCRATE_EXPECT( context, store.store( observations) == 0) ;
	DRIVERCRATE_EXPECT( context, store.load( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == ReleaseObservationStoreState::LOADED) ;
	DRIVERCRATE_EXPECT( context, result.observations.size() == observations.size()) ;
	// 保存前と同じ件数の観測結果がある場合にだけ各要素のround-tripを確認する。
	if( result.observations.size() == observations.size()) {
		DRIVERCRATE_EXPECT( context, observationsEqual( result.observations[0], observations[0])) ;
		DRIVERCRATE_EXPECT( context, observationsEqual( result.observations[1], observations[1])) ;
	}

	const std::span<const LocalOfficialReleaseObservation> empty ;	// 明示的な空snapshot。
	DRIVERCRATE_EXPECT( context, store.store( empty) == 0) ;
	DRIVERCRATE_EXPECT( context, store.load( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == ReleaseObservationStoreState::LOADED) ;
	DRIVERCRATE_EXPECT( context, result.observations.empty()) ;
	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正入力が既存snapshotを変更しないことを検証する。
 *
 * 重複、不正hash、record上限を一時file作成前に拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidInputPreservesState( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore		  store( root) ;						// Production ACLを使わない試験store。
	const LocalOfficialReleaseObservation baseline = makeObservation( L'a') ;	// 既存state。
	const std::array					  baselineList{baseline} ;				// 最初に保存する一件snapshot。
	DRIVERCRATE_EXPECT( context, store.store( baselineList) == 0) ;

	OfficialReleaseObservationStore relativeStore( L"relative-test-root") ;	// 不正な相対root。
	ReleaseObservationStoreResult	result ;								// 不正rootと既存stateの読取り結果。
	DRIVERCRATE_EXPECT( context, relativeStore.load( result) != 0) ;
	DRIVERCRATE_EXPECT( context, relativeStore.store( baselineList) != 0) ;

	const std::array duplicates{baseline, baseline} ;	// 同じbindingを持つ不正snapshot。
	DRIVERCRATE_EXPECT( context, store.store( duplicates) != 0) ;

	LocalOfficialReleaseObservation invalidHash = makeObservation( L'e') ;	// 不正hash観測。
	invalidHash.publishedSha256[0]				= L'D' ;
	const std::array invalidList{invalidHash} ;	// Core検証で拒否するsnapshot。
	DRIVERCRATE_EXPECT( context, store.store( invalidList) != 0) ;

	const std::vector<LocalOfficialReleaseObservation> oversized(
		4'097U, baseline) ;	// 一snapshotのrecord上限を超える入力。
	DRIVERCRATE_EXPECT( context, store.store( oversized) != 0) ;

	DRIVERCRATE_EXPECT( context, store.load( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == ReleaseObservationStoreState::LOADED) ;
	DRIVERCRATE_EXPECT( context, result.observations.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.observations.size() == 1U) {
		DRIVERCRATE_EXPECT( context, observationsEqual( result.observations.front(), baseline)) ;
	}

	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 改ざんsnapshotを再利用せず破棄することを検証する。
 *
 * 同じheaderと表示値でもpayload hash不一致をInvalidatedにする。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testCorruptionInvalidation( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore store( root) ;							// Production ACLを使わない試験store。
	const std::array				observations{makeObservation( L'a')} ;	// 改ざん前の正常snapshot。
	DRIVERCRATE_EXPECT( context, store.store( observations) == 0) ;
	DRIVERCRATE_EXPECT( context, corruptStoredFile( root, STATE_FILE_NAME)) ;

	ReleaseObservationStoreResult result ;	// 改ざん後のload結果。
	DRIVERCRATE_EXPECT( context, store.load( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == ReleaseObservationStoreState::INVALIDATED) ;
	DRIVERCRATE_EXPECT( context, result.observations.empty()) ;

	const std::filesystem::path statePath =
		// 破棄確認対象path。
		std::filesystem::path( root) / STATE_FILE_NAME ;
	std::error_code existsError ;												// File存在確認のI/O error。
	const bool		exists = std::filesystem::exists( statePath, existsError) ;	// 破棄後状態。
	DRIVERCRATE_EXPECT( context, !existsError && !exists) ;
	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式自動探索cacheのmissing、positive／negative往復と空snapshotを検証します。
 *
 * @param[in,out] context Assertion集計先です。
 */
//------------------------------------------------------------------------------
void testDiscoveryCacheRoundTrip( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提directoryがない場合はfile試験を開始しません。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore store( root) ;	// Production ACLを使わない試験store。
	DiscoveryCacheStoreResult		result ;		// Cache load結果。
	DRIVERCRATE_EXPECT( context, store.loadDiscoveryCache( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == DiscoveryCacheStoreState::MISSING) ;

	const std::array entries{
		makeDiscoveryCacheEntry( OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD),
		makeDiscoveryCacheEntry(
			OfficialDiscoveryCacheEntryKind::NO_RECORD)} ;	// 異なる固定rootの二entry。
	DRIVERCRATE_EXPECT( context, isOfficialDiscoveryCacheEntryValid( entries[0])) ;
	DRIVERCRATE_EXPECT( context, isOfficialDiscoveryCacheEntryValid( entries[1])) ;
	DRIVERCRATE_EXPECT( context, store.storeDiscoveryCache( entries) == 0) ;
	DRIVERCRATE_EXPECT( context, store.loadDiscoveryCache( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == DiscoveryCacheStoreState::LOADED) ;
	DRIVERCRATE_EXPECT( context, result.entries.size() == entries.size()) ;
	// 復元件数が一致した場合だけ保存順と全fieldを参照します。
	if( result.entries.size() == entries.size()) {
		DRIVERCRATE_EXPECT( context, discoveryCacheEntriesEqual( result.entries[0], entries[0])) ;
		DRIVERCRATE_EXPECT( context, discoveryCacheEntriesEqual( result.entries[1], entries[1])) ;
	}

	const std::span<const OfficialDiscoveryCacheEntry> empty ;	// 明示的な空cache snapshot。
	DRIVERCRATE_EXPECT( context, store.storeDiscoveryCache( empty) == 0) ;
	DRIVERCRATE_EXPECT( context, store.loadDiscoveryCache( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == DiscoveryCacheStoreState::LOADED) ;
	DRIVERCRATE_EXPECT( context, result.entries.empty()) ;
	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正cache入力が既存snapshotを変更しないことを検証します。
 *
 * 同じ固定rootの重複とschema不一致を一時file作成前に拒否します。
 *
 * @param[in,out] context Assertion集計先です。
 */
//------------------------------------------------------------------------------
void testInvalidDiscoveryCachePreservesState( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提directoryがない場合はfile試験を開始しません。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore	  store( root) ;	// Production ACLを使わない試験store。
	const OfficialDiscoveryCacheEntry baseline =
		// 既存cache。
		makeDiscoveryCacheEntry( OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD) ;
	const std::array baselineList{baseline} ;	// 最初に保存する一件snapshot。
	DRIVERCRATE_EXPECT( context, store.storeDiscoveryCache( baselineList) == 0) ;

	const std::array duplicates{baseline, baseline} ;	// 同じ固定rootを持つ不正snapshot。
	DRIVERCRATE_EXPECT( context, store.storeDiscoveryCache( duplicates) != 0) ;
	OfficialDiscoveryCacheEntry invalidSchema = baseline ;	// 未対応schemaの入力copy。
	++invalidSchema.schemaRevision ;
	const std::array invalidList{invalidSchema} ;	// Public validatorが拒否するsnapshot。
	DRIVERCRATE_EXPECT( context, store.storeDiscoveryCache( invalidList) != 0) ;

	DiscoveryCacheStoreResult result ;	// 不正保存試行後のload結果。
	DRIVERCRATE_EXPECT( context, store.loadDiscoveryCache( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == DiscoveryCacheStoreState::LOADED) ;
	DRIVERCRATE_EXPECT( context, result.entries.size() == 1U) ;
	// 既存一件が残っている場合だけbaselineとの完全一致を確認します。
	if( result.entries.size() == 1U) {
		DRIVERCRATE_EXPECT( context, discoveryCacheEntriesEqual( result.entries.front(), baseline)) ;
	}

	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 改ざんcacheを再利用せず破棄することを検証します。
 *
 * @param[in,out] context Assertion集計先です。
 */
//------------------------------------------------------------------------------
void testDiscoveryCacheCorruptionInvalidation( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提directoryがない場合はfile試験を開始しません。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore store( root) ;	// Production ACLを使わない試験store。
	const std::array				entries{makeDiscoveryCacheEntry(
		   OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD)} ;	// 改ざん前snapshot。
	DRIVERCRATE_EXPECT( context, store.storeDiscoveryCache( entries) == 0) ;
	DRIVERCRATE_EXPECT( context, corruptStoredFile( root, DISCOVERY_CACHE_FILE_NAME)) ;

	DiscoveryCacheStoreResult result ;	// 改ざん後のload結果。
	DRIVERCRATE_EXPECT( context, store.loadDiscoveryCache( result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == DiscoveryCacheStoreState::INVALIDATED) ;
	DRIVERCRATE_EXPECT( context, result.entries.empty()) ;

	const std::filesystem::path cachePath =
		// 破棄確認対象path。
		std::filesystem::path( root) / DISCOVERY_CACHE_FILE_NAME ;
	std::error_code existsError ;												// File存在確認のI/O error。
	const bool		exists = std::filesystem::exists( cachePath, existsError) ;	// 破棄後状態。
	DRIVERCRATE_EXPECT( context, !existsError && !exists) ;
	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Release観測と探索cacheのfile寿命が分離されることを検証します。
 *
 * @param[in,out] context Assertion集計先です。
 */
//------------------------------------------------------------------------------
void testDiscoveryCacheSeparateDiscard( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提directoryがない場合はfile試験を開始しません。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore store( root) ;			// Production ACLを使わない試験store。
	const std::array observations{makeObservation( L'a')} ;	// 独立して残すrelease観測。
	const std::array entries{								// 破棄するcache。
							 makeDiscoveryCacheEntry( OfficialDiscoveryCacheEntryKind::NO_RECORD)} ;
	DRIVERCRATE_EXPECT( context, store.store( observations) == 0) ;
	DRIVERCRATE_EXPECT( context, store.storeDiscoveryCache( entries) == 0) ;
	store.discardDiscoveryCache() ;

	DiscoveryCacheStoreResult	  cacheResult ;			// Cacheだけを破棄した後のload結果。
	ReleaseObservationStoreResult observationResult ;	// 同じrootのrelease観測結果。
	DRIVERCRATE_EXPECT( context, store.loadDiscoveryCache( cacheResult) == 0) ;
	DRIVERCRATE_EXPECT( context, cacheResult.state == DiscoveryCacheStoreState::MISSING) ;
	DRIVERCRATE_EXPECT( context, store.load( observationResult) == 0) ;
	DRIVERCRATE_EXPECT( context, observationResult.state == ReleaseObservationStoreState::LOADED) ;
	DRIVERCRATE_EXPECT( context, observationResult.observations.size() == observations.size()) ;
	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 端末固有binding keyの生成、再読取り、再生成を検証する。
 *
 * 初回だけ生成し、正常fileは安定し、全0 keyは別keyへ再生成されることを試験rootで確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testBindingSecret( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除する専用store root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !created) {
		return ;
	}

	OfficialReleaseObservationStore store( root) ;	// Production ACLを使わない試験store。
	LocalOfficialBindingSecret		first{} ;		// 初回生成key。
	LocalOfficialBindingSecret		repeated{} ;	// 二回目の読取りkey。
	LocalOfficialBindingSecret		replaced{} ;	// 破損後の再生成key。
	bool							regenerated{} ;	// 各呼出しの生成状態。
	DRIVERCRATE_EXPECT( context, store.loadOrCreateBindingSecret( first, regenerated) == 0) ;
	DRIVERCRATE_EXPECT( context, regenerated) ;
	DRIVERCRATE_EXPECT( context, store.loadOrCreateBindingSecret( repeated, regenerated) == 0) ;
	DRIVERCRATE_EXPECT( context, !regenerated) ;
	DRIVERCRATE_EXPECT( context, first == repeated) ;
	DRIVERCRATE_EXPECT( context, corruptBindingSecret( root)) ;
	DRIVERCRATE_EXPECT( context, store.loadOrCreateBindingSecret( replaced, regenerated) == 0) ;
	DRIVERCRATE_EXPECT( context, regenerated) ;
	DRIVERCRATE_EXPECT( context, replaced != first) ;
	const bool replacementNonzero =	// 再生成keyに0以外が含まれる場合true。
		std::any_of( replaced.begin(), replaced.end(),
					[]( const std::byte value) { return value != std::byte{} ; }) ;
	DRIVERCRATE_EXPECT( context, replacementNonzero) ;
	removeTestDirectory( root) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_release_observation_store_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialReleaseObservationStoreTests( TestContext &context)
{
	testRoundTrip( context) ;
	testInvalidInputPreservesState( context) ;
	testCorruptionInvalidation( context) ;
	testDiscoveryCacheRoundTrip( context) ;
	testInvalidDiscoveryCachePreservesState( context) ;
	testDiscoveryCacheCorruptionInvalidation( context) ;
	testDiscoveryCacheSeparateDiscard( context) ;
	testBindingSecret( context) ;
}

} // namespace drivercrate::test
